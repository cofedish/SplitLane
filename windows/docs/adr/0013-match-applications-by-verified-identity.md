# ADR W-0013 — Match applications by verified identity, not by path

**Status:** Accepted
**Date:** 2026-09-23
**Supersedes:** [W-0002](0002-route-on-image-path.md) as the persistent identity of a rule
**Extends:** [W-0010](0010-match-packaged-apps-by-family.md) (package family now read from the process token)

## Context

W-0002 made the image path the routing key, and every rule a path. That broke in the field, on the
development machine, with the product's first target application:

```
rule:     ...\AppData\Local\OpenAI\Codex\bin\247581e40ee272fb\codex.exe   (Include folder)
running:  ...\AppData\Local\OpenAI\Codex\bin\d375f7df50d3b421\codex.exe
```

The Codex updater deleted the hash directory the rule named. The rule was still listed, still
enabled, and matched nothing, so the Codex CLI went DIRECT - the failure the product exists to
prevent. The family rule could not help: W-0003's versioned-directory climb recognises `app-1.2.3` and
`1.2.3`, not a content hash, and not a version directory further up the path
(`IDEA-U\ch-0\241.14494.240\bin\idea64.exe`). A moved folder, a renamed install directory, a packaged
application moved to another drive, and an 8.3 spelling of the same path all fail the same way.

The path is also too broad in the other direction: an "include folder" rule admits any file anyone
can drop into that folder, signed or not.

Measured on the machine, and decisive for the design:

- The two installed copies of `codex.exe` (desktop, VS Code extension) are signed by **different
  certificates from different intermediate CAs** with the same subject. A thumbprint or issuer pin
  would break at nearly every build.
- `codex.exe` has **no version resource**; `ChatGPT.exe` reports `OriginalFilename = chrome.exe`, as
  every Electron application does.
- Verifying the Authenticode signature of the 320 MB `codex.exe` takes **~1.5 s** cold, 45-250 ms warm;
  a catalog-signed system binary takes 4-18 ms.
- `QueryFullProcessImageName` **follows a rename** of the running image, so the file at the reported
  path is the running image, not whatever was put at its old name.
- `GetPackageFamilyName` on a `PROCESS_QUERY_LIMITED_INFORMATION` handle returns the family from the
  token (`OpenAI.Codex_2p2nqsd0c76g0`) regardless of where the package is installed.

## Decision

A rule records an **identity** (`AppIdentity.Kind`), and the engine matches a process against it:

| Kind | Identity | Survives |
|---|---|---|
| `Signed` | verified signer subject (CN, O, L, S, C - canonicalised) + product name and signed `OriginalFilename` (when present, language-neutral) + file name | update, new version, new folder, move, new certificate from the same publisher |
| `Package` | package family name, from the process token | update, move to another drive |
| `Unsigned` | SHA-256 of the file | move; **not** an update |
| `Path` | the schema 1 path | nothing; kept only until migrated |

`MatchMode` keeps its stored values and means, per kind: **Exact** = this binary of this application;
**ExecutableFamily** = also the same publisher's binaries with the same product name, or in the same
folder in any version (`ExecutablePath.FamilyScope`: the directory above a version/hash/GUID directory
when the executable sits directly in it, otherwise the same subfolder under any version). Family is
refused for unsigned files and for platform products (`ProductFamily`: Windows, .NET, Electron,
Node.js, OpenJDK, Python, PowerShell, WebView2), the product-name counterpart of W-0003's shared
directories.

A file at a rule's recorded path whose identity no longer matches - unsigned, other signer, other
bytes - is **blocked** (`IdentityMismatch`), not routed and not sent DIRECT.

Verification happens **off the routing path**. The socket pump decides on cheap evidence (path, file
name, token package family, file size, product name when a product rule needs it). A claim - evidence
that points at a rule - without a signature verdict yields `IdentityPending`: the SYN and datagrams
are dropped while a background worker verifies the file once per version (`ImageCatalog`, keyed on
path + size + write time + file id), then the held connections are decided again. TCP retransmits the
SYN after the initial RTO (1 s on Windows 11), so the first connection of a newly updated application
pays about a second, once.

Existing rules are **migrated** (schema 1 → 2) by the same code in the app and the engine: a file where
the rule says is verified and its identity recorded; a missing file is looked for in the sibling
version/hash directories and adopted only if validly signed by the publisher the rule recorded (the
schema 1 string, compared the way the old code wrote it); anything else becomes
`RuleStatus.NeedsReselection` and routes nothing, with the reason on the rule. The schema 2 document is
written to `configuration.v2.json`; `configuration.json` is never written again, so a pre-schema-2
build installed as a rollback still finds a file it can read.

## Rationale

**Why the signer subject and not the thumbprint.** See the measurements: the thumbprint and the issuing
CA change between builds of the same application; the subject does not. AppLocker's publisher rules
draw the same line (O, L, S, C), for the same reason. EV-only attributes (serial number, business
category, jurisdiction), OU and street are left out because they change without the publisher
changing.

**Why the product name and file name too.** The signer alone is "anything this company signs", which
is the over-breadth the task forbids. Product name separates two applications of one publisher; the
file name separates binaries within a product that has no version resource (most Rust and Go CLIs).
`OriginalFilename` is not what a rule is found by - it is `chrome.exe` for every Electron app and
absent for most CLIs - but when the picked binary has one it must match too, which is what stops a
copy of another binary from the same publisher, renamed to the selected name, from inheriting the rule
(see the review outcome).

**Why the package family from the token.** A path under `WindowsApps` can be imitated by anyone who can
create a directory; a token's package identity is set by Windows at activation.

**Why hold instead of deciding on the claim.** Deciding DIRECT leaks a selected application; deciding
PROXY hands its lane to an impostor with the right file name. Verifying synchronously on the socket
pump would stall every connection on the machine behind a 1.5 s hash and let SYNs overtake their
decisions (the race fixed in dcafb38).

**Why not the parent process.** A child such as `git.exe` started by Codex is another application. The
parent process id is also chosen by the creator (`PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`), so
inheritance by parent would let any process adopt any lane.

**Why block on a mismatch at the recorded path.** Either the application was replaced in place by
something else (inheriting the rule would be wrong) or it updated in place under a new signer (sending
it DIRECT would be a silent leak). Blocking is wrong in neither case and visible in both.

## Consequences

- The Codex rules that stopped matching are re-anchored by migration and match again, including the
  second installation and the helper in the same folder; verified live with `SplitLane.Engine.exe
  --explain` (`docs/DEVELOPMENT.md`).
- **Several installations of one application are one application.** The VS Code copy of `codex.exe` is
  routed by the desktop copy's rule. A rule for "this copy only" does not exist; if it is ever needed,
  it is a path pin on top of an identity, not a return to path matching.
- **Unsigned applications do not follow updates.** Their rule is pinned to bytes; after an update it
  refuses the file at its path until the application is selected again. Their helpers are never
  included. This is the price of an unsigned file having nothing a copy could not also have.
- **A publisher that changes its certificate subject** loses its rules: blocked at the recorded path,
  DIRECT elsewhere, logged either way. Re-selecting fixes it.
- **First connection after an update waits about a second** while the new build is verified.
- **TCP Block now blocks.** A TCP `Block` decision used to be recorded as "leave alone" and went out
  DIRECT; the NAT table now carries a verdict and the packet loop drops Block and Pending.
- **Residual risk: on-disk verification.** The signature is checked on the file at the image path.
  Process herpaderping/ghosting-style tricks can make the mapped image differ from the file; they need
  local code execution, and application control (WDAC/AppLocker) is the control for that, not a
  routing product. Recorded in THREAT_MODEL W-2.
- The engine gained `--explain` (which rule matches which running process, and why) and `--describe
  <exe>` (the identity a rule would record), both unelevated and read-only.

## Review outcome (2026-09-23)

Two independent reviews (correctness, security) and a live `--explain` run changed the design in
these ways:

- **Nothing off the machine is opened.** The engine is LocalSystem; opening `\\host\share\x.exe` - a
  rule path, or the image of a process started from a share - authenticates the machine account to
  that host. `ImageFile.IsLocalPath` admits only local drive letters (fixed, removable, optical, RAM);
  UNC, device and remote-drive paths are never touched, and such an executable is never any selected
  application.
- **Version strings are read language-neutral** (`FILE_VER_GET_NEUTRAL`): from the signed image, not
  its MUI satellite, which the signature does not cover and which made `notepad.exe` report a Russian
  product name on this machine. The same rule now reads the same on every machine in a fleet.
- **The signed `OriginalFilename` is part of the identity when present**, so a copy of another binary
  of the same publisher renamed to the selected name no longer inherits the rule. Every inbox Windows
  tool shares signer and product; this was the only thing telling them apart.
- **Operating-system signers never root a product family** (`ProductFamily.PlatformSigners`),
  independent of the product string's language.
- **A family picked deep inside a versioned bundle covers that folder in any version, not the bundle.**
  Climbing out of the hash directory outright put a Node.js runtime into a Codex tool's family in the
  first live run.
- **A schema 1 rule with no recorded publisher is not migrated onto a file that is now signed**; it is
  `NeedsReselection`.
- **Packages registered from unsigned layouts** (Developer Mode) are not package identities: their
  family comes from a manifest the user wrote.
- **8.3 image names** are expanded before matching.
- A failed or throwing verification, and a hash that cannot be computed, now complete the evidence
  (as not verifying) instead of holding flows forever or re-queueing them.
- The decision path was measured: about 0.57 µs per connection with 20 signed family rules, with no
  allocation of its own (the ancestor walk uses spans).

Closed after the review, on the owner's instruction to fix what can be fixed:

- **A binary with no version resource** is now also told apart by the program database name in its
  signed CodeView record (`PeDebugInfo`): `codex.exe` records `codex.pdb`, its helper
  `codex_code_mode_host.pdb`, and a copy renamed to `codex.exe` keeps its own. Used only where the rule
  has no `OriginalFilename`, so applications that have one are unaffected.
- **A rule waiting to be selected again no longer lets its own file out DIRECT.** A process started from
  exactly the path the rule names is blocked until the rule is re-confirmed; anything elsewhere is
  still unrouted, because nothing established that it is the same application.

Residual, accepted and documented - each with the reason it is not fixed:

- **A binary with neither a version resource nor a CodeView record** (e.g. `node_repl.exe` in the Codex
  runtime) is still identified by signer and file name only. There is nothing else in the signed image
  that survives an update and not a rename; pinning its bytes would break the rule at every update,
  which is the bug this ADR exists to fix.
- **Re-anchoring a missing schema 1 rule trusts the common name schema 1 recorded**, truncated at a
  comma as schema 1 wrote it. A certificate issued to a different organisation whose common name starts
  the same, on a binary placed in a sibling version directory someone else can write to, could be
  adopted. Schema 1 recorded nothing stronger, and refusing every re-anchoring would put the Codex rules
  on this machine - the reason for this work - back to NeedsReselection. Needs a real code-signing
  certificate with a crafted name, and write access to the application's own folder.
- **The engine migrates path rules it is handed**, reading as LocalSystem: whether a local file exists,
  who signed it and the names of version directories beside it can end up in the user's configuration
  and the log. Disclosure only, local files only (nothing off the machine is opened). Closing it means
  impersonating the requesting user for every file access migration makes - the pipe client, or the
  console user when migrating at start - which is sizeable, and a new way to get impersonation wrong in a
  LocalSystem service, for a Low finding.
- Verification is of the file on disk (see above); herpaderping-class tricks need local code execution,
  and application control (WDAC/AppLocker) is the control for that.
- **Verification can be made busy.** A local user can start processes from many large files named like
  a selected binary (or sized like a pinned unsigned one); each is hashed once, on two background
  workers, which delays the first connection of a genuinely selected application waiting behind them.
  Availability only - a held flow is never sent anywhere - and bounded by one verification per file
  version. Rate-limiting or skipping claims was considered and rejected: a legitimately updated
  application arrives as exactly such a claim, and anything that drops claims would let it out DIRECT
  or keep it held; prioritising by location does not help an Exact rule, whose updated binary is found
  by name. Rated Medium by the security review.
- **The first connection of a newly updated application waits for the SYN retransmission** (about a
  second) while it is verified. Holding the SYN and reinjecting it the moment verification finishes
  would remove most of that, but it is a change to the packet path that can only be verified with the
  driver loaded and elevation, which this work could not do; it is left for when it can be.
- **A process started through a hard link with a different name** claims no rule. The name the
  process reports is the link's, and among a file's hard links none is canonical. It is the user
  launching the application differently, not someone else making it leak.
