# ADR W-0014 — A managed policy file that users cannot override

**Status:** Accepted
**Date:** 2026-09-23
**Relates to:** [W-0013](0013-match-applications-by-verified-identity.md) (identity), [W-0004](0004-split-privilege-with-a-named-pipe.md) (privilege split)

## Context

The fleet-readiness review (see `docs/ENTERPRISE_READINESS.md`) found that an organisation running
SplitLane on thousands of machines has no way to put a rule in place:

- The only configuration is `%ProgramData%\SplitLane\configuration*.json`, which every interactive
  user can write (the folder grants `BUILTIN\Users` write access so the unelevated app can save).
- Through the control pipe any interactive user can apply a configuration, stop routing, or install
  an update.
- A path rule is meaningless across machines anyway: user profiles, install drives and version
  directories differ everywhere.

Identity rules (W-0013) are the first rules that mean the same application on every machine.

## Decision

The engine reads an optional **managed policy** from `%ProgramData%\SplitLane\Policy\policy.json`:

```json
{
  "schemaVersion": 1,
  "rules": [ { "identity": { ...output of SplitLane.Engine.exe --describe... }, "action": "Proxy", "matchMode": "Exact" } ],
  "allowUserRules": true,
  "forceRoutingEnabled": true,
  "proxy": { ... },
  "disableSelfUpdate": true
}
```

- **Trust.** The file is used only if neither it nor its folder is a link, both are owned by SYSTEM,
  Administrators or TrustedInstaller, no allow entry lets anyone else write, append, delete, change
  permissions or take ownership of the file, and no allow entry lets anyone else create, delete or
  re-permission files in the folder. It is judged and read through one handle. Otherwise it is
  *rejected*: not applied (the last policy that verified stays in force), logged as an error, reported
  in the engine status and by `--explain`. The service creates the
  `Policy` folder with inheritance cut and only SYSTEM and Administrators in its ACL (users may not
  even read it - see the review outcome below).
- **Rules** must carry an identity (`Signed`, `Package`, `Unsigned`); path rules are ignored and
  reported. They are marked `IsManaged` and looked up in a tier of their own **before** any user rule,
  so no user rule - however specific - can redirect a governed application; a user rule for the same
  application is dropped outright. Managed rules are not pinned to their recorded path, which was
  recorded on the administrator's machine.
- **Revocation** is removal: the folder is watched and the policy re-read on change, so a rule removed
  from the file stops applying within seconds, on every machine that receives the new file.
- `allowUserRules: false` drops the user's rules; `forceRoutingEnabled` keeps routing on and makes the
  control channel refuse `StopRouting`; `proxy` replaces the user's upstream; `disableSelfUpdate` makes
  the update service refuse to check or install.

## Rationale

**A file, not the registry, for now.** Intune (Win32 app / remediation script), Configuration Manager
and Group Policy Preferences all place files; rules are structured data that does not fit ADMX text
elements comfortably. Registry delivery (`HKLM\SOFTWARE\Policies\SplitLane`) remains possible later as
a second source feeding the same `ManagedPolicy` model.

**Judge the file, not the folder's reputation.** `%ProgramData%\SplitLane` is user-writable, so a file
there proves nothing by location. Owner and ACL are what distinguish a file an administrator placed
from one a user planted - a file a user creates is owned by that user.

**Fail open for the policy, visibly.** An untrusted policy is ignored rather than making the engine
refuse to route: otherwise any user who can drop a file decides what the engine enforces. The failure
is an error in the log and in the status, so fleet monitoring can see it.

**Precedence by tier, not by specificity.** With one table, a user's exact rule beats a managed family
rule for the same binary. A separate tier consulted first makes precedence structural. The tier also
verifies claims on managed DIRECT rules instead of short-circuiting them, so a managed DIRECT is not
overridden by a user family rule.

## Review outcome (2026-09-23)

The security review found that the first version could be defeated by any interactive user: the
folder granted Users read access, so a user could open `policy.json` without sharing and make the
engine's read fail, which dropped the policy - and forced routing with it - after which `StopRouting`
was accepted. Fixed:

- The engine keeps **the last policy that verified**. A failed read or a failed trust check is logged
  as an error and reported, and changes nothing; only a file that reads and verifies, or verified
  absence, does.
- The `Policy` folder has **no entry for Users** at all; the engine is its only reader. An existing
  folder that is not owned by Administrators/SYSTEM, or grants non-administrators any right to add,
  delete or re-permission files, has its owner and permissions **reset** by the service.
- The file is **opened once**, sharing read only; its owner and ACL are read from that handle and its
  contents from the same stream. A file or folder that is a **link** is refused. The **folder's owner**
  must be administrative too, since an owner can always rewrite a DACL. Size is capped at 1 MB.
- **Every folder above the policy** must be owned by an administrative principal and let nobody else
  delete, rename or re-permission it (`PolicyFileTrust.AncestryProblem`). `%ProgramData%\SplitLane` is
  created by whichever process gets there first, and one created by a user is fully controlled by
  that user, who could rename it and take the policy with it. A policy that disappears from under a
  folder like that is not taken as revoked - the last verified policy stays - and the service resets
  the state folder's owner and permissions to what it would have created. Checked live: the real
  `C:\ProgramData\SplitLane` chain on the development machine passes; a user-owned one is reported.
- When the policy forces routing and routing is stopped or faulted, a policy reload **starts it again**.
- A policy with managed PROXY rules and no `proxy` is **reported**: the user's proxy then decides where
  "must be proxied" traffic goes, including a forwarder that sends it straight out. Set `proxy` when the
  upstream must be the organisation's.

## Consequences

- An organisation can mandate that an application is proxied (or kept DIRECT), everywhere, by
  identity, and revoke it by removing it - the first fleet-management capability.
- The app does not yet show managed rules; it shows the user's rules. The engine status carries
  `PolicyState`, `PolicyDetail`, `ManagedRuleCount` and `RoutingLockedByPolicy` for the app to display,
  and `--explain` shows the merged result. Showing managed rules read-only in the app is the next step.
- Not covered: a policy-delivered proxy password (the credential is still the user's DPAPI blob), the
  user-writable configuration folder itself, fail-closed behaviour while the engine is stopped, and a
  signed policy. See `docs/ENTERPRISE_READINESS.md`.
- The trust check is unit-tested as a pure function and once for real (a file created by the test
  account is refused). Placing a file as SYSTEM, and the folder creation by the service, have not been
  exercised on a live install: that needs elevation.
