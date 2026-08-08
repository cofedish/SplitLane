# ADR 0005 — Configuration via providerConfiguration + provider messaging, not an App Group

**Status:** Accepted · **Date:** 2026-08-08

## Context

The host app must get the rule set and proxy configuration to the provider, both at start and on
live change. The original design proposed a shared App Group container.

## Decision

Configuration travels through `NETunnelProviderProtocol.providerConfiguration` (authoritative,
persistent, delivered by the system at provider start) and
`NETunnelProviderSession.sendProviderMessage` (live reload). The proxy password travels through
`NEVPNProtocol.passwordReference` as a Keychain persistent reference. No App Group on the critical
path.

## Rationale

- A macOS **system** extension runs as root with a different container root than the user-space
  app, and macOS App Groups require the team-identifier prefix. The common failure is that the app
  writes to one path, the extension reads another, and neither reports an error — the provider
  just sees an empty configuration. That is a bad class of bug to design in.
- `providerConfiguration` is delivered by the system as part of provider startup, so there is no
  window where the provider is running without configuration.
- Both APIs were verified present in the installed SDK.
- Avoiding the App Group also removes an entitlement from both targets, which matters when the
  entitlement situation is already the project's main external risk.

`group.dev.cofe.splitlane` remains reserved for future bulk data (activity history), which is not
on the flow-handling path.

## Consequences

- `providerConfiguration` is a plist in system NE preferences, readable by root and visible to
  `scutil --nc`. **No secret may ever be placed in it.** `ConfigurationCodec` encodes only an
  opaque credential reference, and a unit test asserts no encoded dictionary contains a password.
- Configuration size should stay modest. A few hundred app rules is fine; activity history is not.
- **UNVERIFIED:** that `NETransparentProxyManager.connection` casts to `NETunnelProviderSession`.
  Experiment and fallback recorded in `docs/NETWORKING.md §1.5`. The fallback (bump the generation
  in `providerConfiguration` and restart the session) is correct but drops in-flight flows.
