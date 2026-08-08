---
name: build-and-test
description: Canonical SplitLane build and test commands for both the SwiftPM core and the Xcode app/extension targets, including scheme discovery, DerivedData strategy, SOCKS5 integration testbed, clean rebuilds, build-error triage, and the per-milestone build Definition of Done. Use whenever building, testing, or diagnosing a build failure.
---

# SplitLane build and test

## Discover before you invoke

Never invent `xcodebuild` arguments.

```bash
xcode-select -p                                  # is Xcode even active?
ls *.xcodeproj *.xcworkspace 2>/dev/null
xcodebuild -project SplitLane.xcodeproj -list    # real scheme names
swift package describe --type json | head -40    # SwiftPM targets
```

If `xcode-select -p` prints `/Library/Developer/CommandLineTools`, `xcodebuild` does not exist on
this machine. That is the current state — see `docs/DEVELOPMENT.md` → Gate 1. Core work continues
via SwiftPM regardless.

## Core — works with Command Line Tools alone

```bash
swift build                        # debug
swift build -c release
swift test                         # all unit tests, hermetic, no network
swift test --filter SOCKS5Tests
swift test --filter RuleEngineTests
swift test --filter ConfigurationTests
swift build 2>&1 | grep -E 'warning:|error:'
```

Clean rebuild:

```bash
swift package clean
rm -rf .build          # only if `clean` was not enough
```

## Integration tests (real SOCKS5 server in Docker)

Unit tests never touch the network. Integration tests are opt-in via an environment variable so
`swift test` stays hermetic by default.

```bash
Tools/socks5-testbed/up.sh                        # 10808 no-auth, 10809 user/pass
SPLITLANE_SOCKS5_INTEGRATION=1 swift test --filter Integration
Tools/socks5-testbed/down.sh
docker logs splitlane-socks5                      # when a test fails mysteriously
```

## App + extension — requires Xcode

```bash
xcodegen generate
xcodebuild -project SplitLane.xcodeproj -list
xcodebuild -project SplitLane.xcodeproj -scheme SplitLane \
           -configuration Debug -destination 'platform=macOS,arch=arm64' build
xcodebuild -project SplitLane.xcodeproj -scheme SplitLane clean
```

`SplitLane.xcodeproj` is generated and git-ignored. To change targets, entitlements, capabilities
or embedding, edit `project.yml` and re-run `xcodegen generate`. Never hand-edit
`project.pbxproj`.

If Xcode has the project open while you regenerate, close it first — it will otherwise write back
over the generated file.

## DerivedData

Leave it in the default location and prefer `xcodebuild clean`. Delete it only when diagnosing a
stale-artifact problem:

```bash
rm -rf ~/Library/Developer/Xcode/DerivedData/SplitLane-*
```

A stale **system extension** is a separate problem that DerivedData deletion does not solve — see
the `network-extension-debug` skill.

## Reading build errors

Get the real error, not the summary:

```bash
xcodebuild ... 2>&1 | tee /tmp/build.log | grep -E '^(.*error:|.*warning:)' | head -40
grep -n -B4 -A12 'error:' /tmp/build.log | head -80
```

Common causes on this project:

| Symptom | Cause |
|---|---|
| `requires Xcode` | Command Line Tools only — Gate 1 |
| `No such module 'SplitLaneCore'` | local package not resolved; `xcodegen generate` again |
| `Code Signing Error … no profile` | Gate 2, or `Local.xcconfig` missing `DEVELOPMENT_TEAM` |
| `is not available in macOS 15.0` deprecation warnings | using pre-macOS-15 flow APIs; use the `nw_endpoint_t` forms |
| Sendable / actor-isolation errors in the extension | model the ownership; do not reach for `@unchecked Sendable` |

## Warnings

Warnings are not suppressed. Concurrency, network-lifecycle and signing warnings are treated as
errors until understood. If one is deliberately accepted, a comment states why.

## Milestone build Definition of Done

- Affected targets build with no new warnings (or accepted ones are documented).
- `swift test` passes; new logic has tests.
- Integration tests run when the change touches SOCKS5.
- `git diff` and `git status` reviewed; no secrets.
- `CLAUDE.md` / docs updated if architecture, build workflow, milestone or constraints changed.
- The report distinguishes implemented / compiled / unit-tested / integration-tested / manually
  verified, and claims only what actually happened.

## When the canonical command changes

Update all three: `CLAUDE.md`, `docs/DEVELOPMENT.md`, and this skill. Drift between them is how
the next session ends up running a command that does not work.
