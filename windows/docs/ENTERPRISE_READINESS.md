# Fleet readiness — SplitLane for Windows

Assessment date: 2026-09-23, branch `windows` after the identity and managed-policy work
(ADR W-0013, W-0014). Audience: whoever decides whether SplitLane can be deployed to a managed fleet
of about 10,000 Windows machines, and whoever builds what is missing.

**Verdict: not ready for fleet deployment yet.** Unit and integration tests pass, and routing has been
verified live on single machines; nothing has been run on more than one machine, and the live
WinDivert check of identity (`tools/verify-identity.ps1`) is still pending.

Decisions by the owner (2026-09-23) that shape the plan below:

- **Code signing is the deploying organisation's to do**, with its own certificate, as part of
  packaging for its fleet. SplitLane ships unsigned; that is a deployment step, not a product gap.
- **Selected applications going DIRECT while the engine is down is accepted** - it is how the platform
  behaves, documented - but **the service must restart itself**. Done: see below.
- **Central monitoring is covered by other tools** the organisation already runs. What SplitLane owes
  them is something to collect: the log file and the status the engine reports.
- **DNS not being proxied is accepted**, with the consequences written down - `NETWORKING.md` §7, "What
  an unproxied lookup costs" and "When it matters".

## Current behaviour

| Area | What the code does today | Risk at fleet scale |
|---|---|---|
| Proxy unreachable | Selected TCP fails closed: the relay's SOCKS5 handshake fails and the connection is closed, never DIRECT (`RedirectListener`). Up to the handshake timeout (10 s default) per connection. Selected UDP is dropped. | Correct. Long stalls look like hung apps. |
| Engine stopped, crashed, upgrading, booting | **Fail-open, accepted.** Divert handles close with the process and selected apps go DIRECT until it is back. **Now restarted:** the MSI sets service recovery (restart on failure, also on a non-zero exit), and inside a running engine a divert thread that dies, or a handle that refuses a thousand receives in a row, makes the engine restart routing itself with a growing pause (2 s, 10 s, 30 s, 1 min, then every 5 min) - the case the service manager cannot see, because the process is alive. | Gaps are now seconds, not "until someone notices". Accepted. |
| DNS | Not proxied when resolved through the Windows DNS Client; answers are sniffed to send hostnames to the proxy (`ATYP=DOMAIN`). An application's own DoH or UDP/53 is proxied like the rest of its traffic. | Accepted. Names are visible to the local resolver; blocked or intranet-only names fail. When that matters: `NETWORKING.md` §7. |
| UDP / QUIC | Relayed through SOCKS5 UDP ASSOCIATE by default (ADR W-0012); dropped - never sent DIRECT - when the proxy refuses, the 64-lane pool is full, or the datagram is IPv6. | IPv6 UDP of selected apps always fails. P2 |
| Rule delivery and revocation | **New:** an administrator-owned policy file with identity rules users cannot override, revoked by removal (W-0014). The user file is still writable by every interactive user, and there is no registry/ADMX source. | Policy exists; delivery tooling and UI do not. P0 → partly done |
| Admin rights | Engine is a LocalSystem service; app is unelevated. The pipe (11 closed request kinds) lets any interactive user apply a configuration, stop routing (**now refused under `forceRoutingEnabled`**), and install a signed update (**now refused under `disableSelfUpdate`**). | Remaining: `ApplyConfiguration` is still open to any user for their own rules. P1 |
| Credential | Proxy password is a DPAPI LocalMachine blob in the user-writable folder; any local process that can read the file can decrypt it. | P1 |
| Logs | `%ProgramData%\SplitLane\logs\engine.log`, 4 MB plus one rollover. No Event Log, no ETW. Identity decisions are now logged once per file version with signer, rule and outcome; activity (500 entries) is memory-only. | No central collection, no durable audit. P1 |
| Health | No telemetry of its own. The engine log (`%ProgramData%\SplitLane\logs\engine.log`) records routing faults, restarts, policy load/refusal and identity decisions; `--explain` answers "why is this app not routed" locally. | Collected by the organisation's existing tooling. Not a SplitLane blocker. |
| Agent update / rollback | Signed manifest + hashed MSI via msiexec as SYSTEM, user-triggered; downgrade blocked by the MSI. **New:** schema 2 configuration is written beside the schema 1 file, so a rollback still finds a readable file. Policy can turn self-update off. | IT cannot pin versions except by turning self-update off. P1 |
| Deployment | Per-machine MSI, silent `/qn`, driver shipped. Binaries are unsigned; the organisation signs them (every PE and the MSI) with its own certificate when it packages for its fleet. Uninstall leaves `%ProgramData%\SplitLane` (configuration, credential, logs). | Signing is the organisation's step; without it WDAC/AppLocker fleets block the service. |

## Plan, by priority

**1. Managed policy, the rest of it.** The engine enforces it (W-0014). Remaining: the app does not show
managed rules - an employee sees only their own rules and cannot tell that an application is proxied, or
that routing cannot be paused, because of the organisation's policy; a registry source
(`HKLM\SOFTWARE\Policies\SplitLane`) and an ADMX template for Group Policy/Intune; a policy-delivered
proxy credential.
Acceptance: a policy placed as SYSTEM applies on a live install within 5 s; the app lists managed rules
read-only with "managed by your organisation" and does not offer to pause routing when it is forced;
removing a rule from the policy revokes it within 5 s.

**2. Live verification.** Run `tools/verify-identity.ps1` elevated on a test machine, then an MSI
install on a clean VM that checks the recovery actions (`sc qfailure SplitLane`) and kills the engine.
Acceptance: the script reports PASS for update and move; the service restarts within 10 s of a kill.

**3. Lock down state (P1).** Configuration read-only for users once a policy disallows user rules;
`credential.bin` readable by SYSTEM only.
Acceptance: an unelevated user cannot read `credential.bin`, or write the configuration when policy says so.

**4. Durable decision audit (P1).** Rotating JSONL of proxied, blocked and identity-mismatch decisions
with rule and process identity, for the organisation's collectors to pick up.
Acceptance: after a restart the previous hour's decisions are present, each with the matched rule's
identity key.

**5. Update governance (P1).** Version pinning / allowed range via policy (self-update can already be
turned off).
Acceptance: with a pin, a newer signed manifest is reported and not offered.

**6. IPv6 UDP (P2).** Relay, or visibly block with a counter, a selected application's IPv6 UDP.

Organisation-side, not SplitLane work: sign every PE and the MSI with the organisation's certificate;
collect `engine.log` with existing tooling; decide whether the DNS consequences in `NETWORKING.md` §7
matter for the applications being selected.

## Done in this change

- Application identity survives updates, moves and certificate renewals (W-0013), with migration of
  existing rules and explicit `NeedsReselection` where it cannot be proven.
- TCP `Block` decisions are enforced (they previously went out DIRECT).
- Managed policy, engine side (W-0014): trust check on owner and ACL, identity-only rules in a
  precedence tier, revocation by removal, forced routing, managed proxy, self-update off.
- `--explain` and `--describe` for support and for authoring policy rules.
- Service recovery in the MSI, and routing restarted by the engine itself when a divert thread dies.
- Two residual identity risks closed: binaries with no version resource are also told apart by the
  program database name in their signed image; a rule waiting to be selected again blocks its own file
  instead of letting it out DIRECT.
- Schema 2 configuration kept in its own file for rollback safety.
- Hardening from the security review: the LocalSystem engine never opens UNC or remote-drive paths
  (machine-account coercion); the last verified policy survives a failed read; the policy folder is
  administrator-only and repaired if not; the configuration file and rule count are bounded; one
  migration runs at a time; version strings are read language-neutral from the signed image.

## Verification levels reached

| | |
|---|---|
| Unit-tested | identity matching, migration, policy merge and trust rules (450 Core tests) |
| Integration-tested, real files and processes | WinVerifyTrust on real binaries, a process started from an "updated" copy verified and relayed through a real SOCKS5 server, background migration, policy load/revoke (136 Engine tests) |
| Live, unelevated, this machine | `--explain` on the real configuration and processes: migrated Codex rules match the updated `codex.exe`, its second installation and its helper |
| **Not reached** | WinDivert holding a real SYN during verification (`tools/verify-identity.ps1`, needs an elevated terminal); a policy placed by Intune/SCCM as SYSTEM; any multi-machine run |
