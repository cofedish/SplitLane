# ADR W-0011 — Updates are applied by the engine, and only if signed

**Status:** Accepted
**Date:** 2026-08-21
**Relates to:** [W-0004](0004-split-privilege-with-a-named-pipe.md) (split privilege), [W-0009](0009-ship-the-driver-in-the-package.md) (ship the driver)

## Context

Every update so far has been a manual MSI download and install. That is fine for the first
installation and wrong for the twentieth: a fix nobody installs is a fix nobody has.

Two things make this harder than it is for an ordinary application. The engine is a `LocalSystem`
service, so whatever installs an update is running with full privileges — and nothing SplitLane ships
is code-signed, so Windows itself will not vouch for what gets installed. An updater built without
answering that is not a convenience; it is a way to run arbitrary code as SYSTEM on every machine
that installed SplitLane.

## Decision

**The engine applies updates, and a release is only an update if it is signed by the release key.**

- CI publishes `update.json` — version, installer URL, SHA-256 — and `update.json.sig`, an ECDSA
  P-256 signature over the manifest bytes exactly as published.
- The public key is compiled into the build (`ReleaseKey.PublicKeySpki`). The private half lives in
  the release pipeline's secrets and signs nothing else.
- The engine verifies the signature **before parsing the document**, hashes the downloaded installer
  against what the verified manifest said, and takes the version and the URL from that document
  rather than from anywhere they could be substituted.
- The installer URL is additionally constrained to HTTPS on `github.com`, `*.github.com` or
  `objects.githubusercontent.com` (`UpdateManifest`). The URL comes out of a signed document, so this
  only matters if the key ever leaks — which is exactly when it matters.
- A release published without the signing secret gets **no manifest**, not an unsigned one.

**The engine checks; the person installs.** Applying an update restarts the service and drops every
relayed connection. That is a reasonable thing to ask for and a bad thing to spring on someone
mid-call, so `CheckForUpdate` happens once a day on its own and `ApplyUpdate` never happens without
being asked.

**The request carries nothing.** `ApplyUpdate` has no version, no URL and no file name — it says
*when*, not *what*. An unelevated window cannot name what a SYSTEM service installs, which is the
same rule the control channel has had since W-0004 and the reason its vocabulary is a closed enum.

The MSI stays the payload. It already knows how to stop the service, replace the files, keep the
configuration and start again; a second mechanism that did the same thing differently would be a
second mechanism to get wrong.

## Consequences

- Updates arrive without a consent prompt, because the service applying them is already `LocalSystem`.
  This is the payoff and the responsibility in the same sentence.
- Losing the private key means being unable to publish updates that existing installations accept.
  Rotating it means shipping a build with a new public key first, and installations that never take
  that build stop updating. It is worth treating like the credential it is.
- The check talks to GitHub once a day from a service, on a machine whose owner installed a network
  tool. It is a fixed address, and it can be seen in the engine log.
- This does **not** remove the SmartScreen warning, which needs a code-signing certificate. The
  signature here protects the delivery channel, not the reputation of the binary.
- Verification is pure and lives in `SplitLane.Core`, reachable from tests with no network and no key
  material checked in — each test makes its own pair, so no test can pass by being handed the real
  one.
- Any interactive user can ask for an install, because the control channel is open to every one of
  them (THREAT_MODEL W-7, W-12). They choose when, never what. An organisation that wants to control
  updates itself sets `disableSelfUpdate` in the managed policy (ADR W-0014), and the engine then
  refuses both to check and to install.

## Status of delivery

The signing pipeline is verified end to end: a published manifest is accepted by the key the build
ships and an edited copy is refused. The repository is public, and
`https://github.com/cofedish/SplitLane/releases/latest/download/update.json` answers an anonymous
request with HTTP 200 (checked 2026-09-23), so an installation can reach it. An install through the
updater has not been run.

## Alternatives considered

**A separate updater executable.** More moving parts, another binary to sign and to trust, and it
would need elevation of its own. The service is already privileged and already running.

**winget.** No code to write, but updating stays a thing the person has to remember to do, and the
community repository expects signed artifacts.

**Trusting TLS alone.** TLS says the bytes came from the host named in the URL. It says nothing about
a compromised release, a redirected host, or a mirror — and the consequence here is SYSTEM.
