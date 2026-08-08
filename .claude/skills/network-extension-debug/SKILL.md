---
name: network-extension-debug
description: Diagnose SplitLane's System Extension and Network Extension problems — activation, approval state, entitlements, signing, provider startup, flow attribution, OSLog inspection, extension replacement, and known failure modes. Use when the extension will not install, will not activate, will not start, will not update, or when flows are not reaching the provider or are being attributed to the wrong application.
---

# NetworkExtension / SystemExtension debugging

Work top-down. Most "the proxy does not work" reports are actually "the extension is not
activated" or "the configuration is disabled".

## Triage ladder

```bash
# 1. Is the extension installed and activated?
systemextensionsctl list

# 2. Is there an NE configuration, and is it connected?
scutil --nc list

# 3. Is the provider process alive?
pgrep -fl SplitLaneProxyExtension

# 4. Is the provider saying anything?
log stream --predicate 'subsystem == "dev.cofe.splitlane"' --info --debug

# 5. What does the system think?
log stream --predicate 'subsystem == "com.apple.networkextension"' --info
log show --predicate 'process == "sysextd" OR process == "nesessionmanager"' --last 10m
```

Expected healthy state: `systemextensionsctl list` shows
`dev.cofe.splitlane.proxyextension … [activated enabled]`, and `scutil --nc list` shows the
SplitLane configuration as `Connected`.

## Activation states and what they mean

| State | Meaning | Action |
|---|---|---|
| `[activated waiting for user]` | Awaiting approval | System Settings → General → Login Items & Extensions → Network Extensions |
| `[activated waiting for nsextension]` | Approved, not yet loaded | Usually transient; check provider logs |
| `[terminated waiting to uninstall on reboot]` | Old copy pending removal | Reboot, or `systemextensionsctl uninstall` |
| `[activated enabled]` | Healthy | — |
| Nothing listed | Activation never ran or failed early | Check the app's `OSSystemExtensionRequest` delegate errors |

For locally-built, non-notarized extensions on Apple Silicon:

```bash
systemextensionsctl developer on      # then re-activate; may need a reboot
```

The app must be in `/Applications`. macOS refuses to activate a system extension from
`~/Downloads`, DerivedData, or a Desktop folder, and the error is not obvious.

## Signing and entitlements

```bash
EXT=/Applications/SplitLane.app/Contents/Library/SystemExtensions/dev.cofe.splitlane.proxyextension.systemextension

codesign -dv --verbose=4 /Applications/SplitLane.app
codesign -dv --verbose=4 "$EXT"
codesign -d --entitlements - /Applications/SplitLane.app
codesign -d --entitlements - "$EXT"
codesign --verify --deep --strict --verbose=2 /Applications/SplitLane.app
spctl -a -vvv -t exec /Applications/SplitLane.app
```

Required on the **app**: `com.apple.developer.system-extension.install`.
Required on the **extension**: `com.apple.developer.networking.networkextension` containing
`app-proxy-provider-systemextension`.

Checklist when validation fails:
- Extension bundle identifier is a dotted child of the app's (`dev.cofe.splitlane` →
  `dev.cofe.splitlane.proxyextension`).
- Both signed by the same team.
- `NEMachServiceName` / `NetworkExtension` keys present in the extension's `Info.plist`.
- The entitlement is actually provisioned — a free/personal team cannot have it at all, which
  looks like a signing bug but is an account problem. See `docs/DEVELOPMENT.md` → Gate 2.

## The extension will not update

macOS caches the activated extension by version. A rebuilt extension with the same version is
ignored — silently.

```bash
# bump CFBundleVersion first, then:
systemextensionsctl list
systemextensionsctl uninstall <TEAMID> dev.cofe.splitlane.proxyextension
# relaunch the app to re-activate
```

Deleting DerivedData does nothing for this. If behaviour does not match the source you just
edited, suspect a stale extension before suspecting your code.

## The provider is running but sees no flows

In order:

1. `NETransparentProxyManager.isEnabled == true`. An existing-but-disabled configuration looks
   identical from the app side.
2. `setTunnelNetworkSettings` actually succeeded. A rule that violates the documented restrictions
   makes it fail, and then the provider receives nothing at all. The restrictions
   (`docs/NETWORKING.md §1.4`) that are easy to trip:
   - port `"53"` is prohibited
   - `matchLocalNetwork` must be nil
   - `matchDirection` must be `.outbound`
   - wildcard address requires a non-zero port, and vice versa
3. Loopback is excluded from wildcard rules **by design** — traffic to `127.0.0.1` will never
   appear. That is the loop-prevention guarantee, not a bug.
4. `startProxy` completed without error and the completion handler was actually called.

## Flow attribution problems

```bash
log stream --predicate 'subsystem == "dev.cofe.splitlane" AND category == "routing"' --info
```

- `sourceAppSigningIdentifier` may be **empty** for system-process flows. SplitLane routes those
  DIRECT by design.
- Electron/Chromium apps emit flows from helper processes
  (`com.example.App.helper.Renderer`), not the main bundle identifier. This is why matching is on
  the bundle family (ADR 0006). If a selected app is not being proxied, log the identifier that
  actually arrived before assuming the rule engine is broken.
- `remoteHostname` is nullable — BSD-socket clients connecting to a literal IP have none.
- To confirm identity properly, resolve `sourceAppAuditToken` with
  `SecCodeCopyGuestWithAttributes(kSecGuestAttributeAudit:)`. Expensive; cache on
  `(pid, pidversion)`.

## Verifying the proxy lane end-to-end

```bash
sudo lsof -nP -iTCP:10808            # only the extension should be a client
nc -vz 127.0.0.1 10808               # upstream reachable at all?
log stream --predicate 'subsystem == "dev.cofe.splitlane" AND category == "relay"' --info
```

A selected app failing to connect while the proxy is down is **correct** (fail-closed, ADR 0003).
Check the UI is reporting it before treating it as a defect.

## Known failure modes

| Symptom | Cause |
|---|---|
| `OSSystemExtensionErrorValidationFailed` | signing/entitlement mismatch, or app not in `/Applications` |
| `OSSystemExtensionErrorRequestSuperseded` | two activation requests in flight; serialise them |
| Approval prompt never appears | app not in `/Applications`, or a previous denial is cached — check `systemextensionsctl list` |
| Provider starts then immediately stops | `setTunnelNetworkSettings` failed; check the rule restrictions above |
| Everything DIRECT after a crash | provider restarting; flows fail open during the window (F-4) |
| Selected app broken entirely | UDP fail-closed with no TCP fallback (`docs/NETWORKING.md §5`) |

## When you find a new failure mode

Add it to the table above and to `docs/TROUBLESHOOTING.md`. This skill is only useful if it stays
ahead of the problems already solved once.
