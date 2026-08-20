# ADR W-0004 — Split privilege across two processes joined by a named pipe

**Status:** accepted
**Date:** 2026-08-20
**Windows counterpart of:** ADR 0005 (provider configuration, not an app group)

## Context

Diverting packets needs administrative rights. A configuration UI does not.

The options:

1. **One elevated application.** Simplest to build. Every line of WPF, every binding, every
   third-party font resolution and every file dialog then runs as administrator.
2. **Two processes, joined by IPC.** The engine elevated, the app not.
3. **Two processes, with the engine as a Windows service.** As above, plus survives logout and starts
   at boot.

## Decision

Two processes joined by a named pipe. The engine is a console process for now; a service host is
future work, and the control channel is shaped so that moving to one changes nothing on the app side.

## Rationale

An elevated UI is a large attack surface for a small convenience. The app opens file dialogs, parses
version resources from arbitrary executables, builds certificate chains, and renders a themed
interface — none of which needs privilege, and all of which would have it.

The split also produces a boundary worth having for its own sake: it forces every privileged
operation to be named. `EngineRequestKind` has nine members, and the exercise of enumerating them is
what makes it obvious that none of them should take a file path or a command line.

## The contract

- **Closed vocabulary.** A flat request record with a `Kind` enum, not a polymorphic hierarchy. The
  elevated side can validate it by reading it, with no converter resolving a type name out of
  attacker-controlled JSON.
- **Explicit ACL.** The interactive user, administrators, SYSTEM. Nothing else. Without an explicit
  ACL, a pipe created by a service is reachable by every account on the machine, which would let any
  local user reconfigure the proxy or read the rule set.
- **Bounded frames.** Length-prefixed, and the prefix is checked against a 1 MB ceiling *before* a
  byte is allocated. A length an unprivileged caller controls is an allocation an unprivileged caller
  controls.
- **One request per connection.** A long-lived multiplexed session would need its own framing state
  machine on the elevated side, and the app polls rarely enough that the extra connection costs
  nothing worth optimising.
- **Shared validation.** A configuration handed over the pipe goes through the same
  `ConfigurationValidator` as the engine's own file, so an app-supplied rule cannot bypass the
  family-matching guard of ADR W-0003.

## Consequences

**"The engine is not running" is an ordinary state, not an error.** It is what a machine looks like
before the user has started it. Every client call is allowed to fail that way, the connect timeout is
400 ms so a poll cannot freeze the window, and the UI presents it as a step to take rather than a
fault.

**The app can be used before the engine ever runs.** It writes the configuration file itself and asks
the engine to reload if one is listening. Rules can be set up on a machine with no driver installed.

**Configuration is machine-wide.** `%ProgramData%\SplitLane`, because a per-user path would be
readable by exactly one of the two processes. On a shared computer every account's rules are visible
to every other account — a real property, stated in the Settings page, and one the divert layer would
force anyway since interception is machine-wide.

**The password needs its own store.** DPAPI at machine scope, in a separate file, so the engine can
read it as a service account and it never appears in the JSON someone would attach to a bug report.
