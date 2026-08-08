# SplitLane Troubleshooting

## Build

### `xcodebuild: error: tool 'xcodebuild' requires Xcode`

Only Command Line Tools are installed. See `docs/DEVELOPMENT.md` → Gate 1. `swift build` and
`swift test` for `SplitLaneCore` still work in this state — most of the codebase is reachable
without Xcode.

### `xcodegen` changes do not appear

`SplitLane.xcodeproj` is generated. Re-run `xcodegen generate`. If Xcode has the project open,
close it first; Xcode will otherwise rewrite the file you just generated.

### Swift 6 concurrency errors in extension code

The extension runs callbacks on NE-owned queues. Types crossing those boundaries must be `Sendable`
or explicitly isolated. Do not silence with `@unchecked Sendable` — model the ownership. A relay
owns its own state and is confined to its own queue; that is the pattern to follow.

## System extension

### `systemextensionsctl list` shows `[activated waiting for user]`

Approval is pending: System Settings → General → Login Items & Extensions → Network Extensions.
On Apple Silicon a locally-built extension usually also needs `systemextensionsctl developer on`.

### `Code Signature Invalid` / `OSSystemExtensionErrorValidationFailed`

```bash
codesign -dv --verbose=4 /Applications/SplitLane.app/Contents/Library/SystemExtensions/dev.cofe.splitlane.proxyextension.systemextension
codesign -d --entitlements - /Applications/SplitLane.app
```

Check: the extension's bundle identifier is a prefix-child of the app's; both are signed by the
same team; the app is in `/Applications` (system extensions are only activated from there); the
NetworkExtension entitlement is present on both.

### The extension will not update to a new build

macOS caches the activated extension by version. Bump `CFBundleVersion`, then:

```bash
systemextensionsctl list
systemextensionsctl uninstall <TEAMID> dev.cofe.splitlane.proxyextension
```

Then re-activate from the app. Deleting DerivedData alone does not help.

### The provider is never asked about flows

Check in order:
1. `systemextensionsctl list` → `[activated enabled]`
2. `scutil --nc list` → the SplitLane configuration exists and is Connected
3. `NETransparentProxyManager.isEnabled == true` — an existing-but-disabled config looks
   identical to a working one from the app's side
4. The network settings actually applied — a rule violating the restrictions in
   `docs/NETWORKING.md §1.4` makes `setTunnelNetworkSettings` fail, and the provider then sees
   nothing at all. Port `"53"`, a non-nil `matchLocalNetwork`, or a non-outbound direction are the
   usual causes.

## Runtime

### A selected app is not being proxied

1. Confirm the identifier the provider actually sees:
   `log stream --predicate 'subsystem == "dev.cofe.splitlane" AND category == "routing"' --info`
2. Compare it with the rule. Electron/Chromium apps do their networking from helper processes —
   `com.example.App.helper` — which is exactly why `RuleEngine` matches the bundle family. If the
   helper identifier is not a dotted descendant of the rule identifier, the rule needs to name it
   explicitly.
3. Loopback and link-local destinations are deliberately never proxied
   (`docs/NETWORKING.md §3`).
4. If the flow never appears at all, the provider is not running — see above.

### A selected app breaks entirely when enabled

Most likely UDP fail-closed with no TCP fallback (`docs/NETWORKING.md §5`). Filter the log for
`udpNotSupported`. Confirm by toggling the app off and retesting.

### Everything is slow / the app hangs

Look for a stalled relay: a flow opened but never closed, no bytes moving. Check whether the
SOCKS5 upstream is actually accepting connections:

```bash
nc -vz 127.0.0.1 10808
sudo lsof -nP -iTCP:10808
```

Fail-closed means an unreachable proxy produces failed connections for selected apps, by design —
that is not a bug, but the UI should be showing the error.

### Suspected proxy loop

`docs/NETWORKING.md §3` has the verification procedure. Symptoms would be a rapidly growing flow
count and an unresponsive provider. The platform guarantee (wildcard rules exclude loopback) makes
this very unlikely; if it happens, the first thing to check is whether a rule with an explicit
loopback address was introduced.

## Logs

```bash
log stream --predicate 'subsystem == "dev.cofe.splitlane"' --info --debug
log show   --predicate 'subsystem == "dev.cofe.splitlane"' --last 15m --info
log stream --predicate 'subsystem == "com.apple.networkextension"' --info    # system side
```

Categories: `app`, `extension`, `provider`, `routing`, `configuration`, `socks5`, `relay`, `ipc`,
`security`.

Nothing sensitive is logged: no passwords, no payloads, no tokens. If a log line would reveal any
of those, it is a bug.
