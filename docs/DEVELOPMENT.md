# SplitLane Development

## Machine of record

| | |
|---|---|
| Hardware | MacBook Air, Apple Silicon (M4), arm64 |
| macOS | 15.6 (24G84) |
| Swift | 6.1.2 (swiftlang-6.1.2.1.2), target `arm64-apple-macosx15.0` |
| SDK | `MacOSX15.5.sdk` (Command Line Tools) |
| Deployment target | macOS 15.0 — see `docs/NETWORKING.md §1.3` for why |

## Two build systems, on purpose

`SplitLaneCore` is a SwiftPM library and `SplitLane` / `SplitLaneProxyExtension` are Xcode targets.
This is not accidental duplication:

- SwiftPM builds and tests **today**, with Command Line Tools only, no Xcode, no signing, no
  approved system extension. That covers the rule engine, the SOCKS5 protocol implementation,
  configuration coding and validation, and IPC messages — i.e. nearly all of the logic where a
  bug can actually hide.
- The app and the extension need Xcode because a `.systemextension` has to be embedded, signed,
  and entitled, and only `xcodebuild` does that.

The Xcode project consumes `Sources/SplitLaneCore` as a local SwiftPM package, so there is exactly
one copy of the code.

## Everyday commands

### Core (works now)

```bash
swift build                          # debug build of SplitLaneCore
swift build -c release
swift test                           # all unit tests (hermetic, no network)
swift test --filter SOCKS5Tests
swift test --filter RuleEngineTests
swift build 2>&1 | grep -E 'warning|error'
```

### Integration tests against a real SOCKS5 server

Unit tests never touch the network. Integration tests run against a real SOCKS5 server in Docker
and are skipped unless explicitly enabled.

```bash
Tools/socks5-testbed/up.sh                                  # 127.0.0.1:11080 (no auth)
                                                            # 127.0.0.1:11081 (user/pass)
SPLITLANE_SOCKS5_INTEGRATION=1 swift test
Tools/socks5-testbed/down.sh
```

The origin server in the testbed publishes no ports, so it is unreachable from the host. A
successful response through the proxy is therefore positive proof the bytes traversed it, rather
than a test that would pass either way. See `Tools/socks5-testbed/README.md`.

### App + extension (requires Xcode)

```bash
xcodegen generate                                           # project.yml -> SplitLane.xcodeproj
xcodebuild -project SplitLane.xcodeproj -list               # discover schemes; never invent args
xcodebuild -project SplitLane.xcodeproj -scheme SplitLane \
           -configuration Debug -destination 'platform=macOS,arch=arm64' build
```

`SplitLane.xcodeproj` is **generated and git-ignored**. Never hand-edit `project.pbxproj`; change
`project.yml` and regenerate. This is how the project satisfies "protect Xcode project files" —
there is no pbxproj to corrupt.

DerivedData: leave it in the default location. Use `xcodebuild clean` for a clean rebuild rather
than deleting DerivedData by hand, except when diagnosing a stale-extension problem, where
`rm -rf ~/Library/Developer/Xcode/DerivedData/SplitLane-*` is the documented step.

## External gates

These cannot be resolved by inspecting the repo, the SDK, or local tooling. They need a human.

### Gate 1 — Install Xcode  *(blocks M1 onward)*

`xcodebuild` is not present; only Command Line Tools are installed.

```bash
xcode-select -p          # currently /Library/Developer/CommandLineTools
```

Install Xcode from the App Store (or developer.apple.com/download), then:

```bash
sudo xcode-select -s /Applications/Xcode.app/Contents/Developer
sudo xcodebuild -license accept
xcodebuild -version      # verify
```

**Verify:** `xcodebuild -version` prints a version and `xcode-select -p` points into `Xcode.app`.

### Gate 2 — Apple Developer Program membership  *(blocks M3 onward)*

```bash
security find-identity -v -p codesigning     # currently: 0 valid identities found
```

The entitlement `com.apple.developer.networking.networkextension` with the value
`app-proxy-provider-systemextension`, and `com.apple.developer.system-extension.install`, are
**not available to free/personal teams**. A paid membership (99 USD/yr) is required. On some
accounts the NetworkExtension capability additionally requires a request to Apple.

Steps: enrol → Xcode → Settings → Accounts → add Apple ID → Manage Certificates → create a
Development certificate → set `DEVELOPMENT_TEAM` in `Local.xcconfig` (git-ignored).

**Verify:** `security find-identity -v -p codesigning` lists an "Apple Development" identity, and
the App IDs for `dev.cofe.splitlane` and `dev.cofe.splitlane.proxyextension` show Network
Extensions + System Extension capabilities in the developer portal.

### Gate 3 — System Extension approval  *(blocks M3 runtime verification)*

macOS requires the user to approve a system extension:
System Settings → General → Login Items & Extensions → Network Extensions → enable SplitLane.

For a locally-built, non-notarized extension on Apple Silicon, `systemextensionsctl developer on`
is usually also required, which needs SIP considerations and sometimes a reboot:

```bash
systemextensionsctl developer on
systemextensionsctl list                # confirm state [activated enabled]
```

**Verify:** `systemextensionsctl list` shows `dev.cofe.splitlane.proxyextension` as
`[activated enabled]`.

## Identifiers

| Component | Identifier |
|---|---|
| Host app | `dev.cofe.splitlane` |
| Proxy extension | `dev.cofe.splitlane.proxyextension` |
| App Group (reserved, not on critical path) | `group.dev.cofe.splitlane` |
| OSLog subsystem | `dev.cofe.splitlane` |
| Keychain service | `dev.cofe.splitlane.proxy-credentials` |

These are fixed. Do not change them casually — the extension identifier in particular is baked
into NE preferences and changing it strands the installed extension. If the team cannot use them,
record the substitute in an ADR rather than editing this table silently.

## Local configuration

`Local.xcconfig` is git-ignored and holds machine-specific signing values:

```
DEVELOPMENT_TEAM = XXXXXXXXXX
CODE_SIGN_STYLE = Automatic
```

`Local.xcconfig.example` is committed as the template. Never commit the real team ID or any
certificate.

## Logging while developing

```bash
# everything from SplitLane, live
log stream --predicate 'subsystem == "dev.cofe.splitlane"' --info --debug

# routing decisions only
log stream --predicate 'subsystem == "dev.cofe.splitlane" AND category == "routing"' --info

# last 10 minutes, after the fact
log show --predicate 'subsystem == "dev.cofe.splitlane"' --last 10m --info
```

## Code style

Modern Swift, deployment target macOS 15. Structured concurrency where it improves lifecycle
clarity; GCD where the API is callback-based and wrapping it would add nothing. No force unwraps
in production paths. No blocking network work on the main thread. Small types, explicit ownership,
structured errors, proper cancellation.

Warnings are not suppressed. A warning in concurrency, network lifecycle, or signing code is
treated as an error until understood. Accepted warnings get a comment saying why.
