#!/usr/bin/env bash
# Type-check the app and extension targets without Xcode.
#
# `xcodebuild` is unavailable with Command Line Tools alone (docs/DEVELOPMENT.md → Gate 1), but
# swiftc can still type-check both targets against the real macOS SDK. That catches missing
# overrides, wrong signatures, ambiguous types and concurrency errors — everything short of
# linking, signing and embedding.
#
# This is how "the app and extension compile" is verified before Xcode exists on the machine.
# It is not a substitute for a real build; it is the strongest check available without one.
set -euo pipefail

cd "$(dirname "$0")/.."

SDK="$(xcrun --show-sdk-path --sdk macosx)"
TARGET="arm64-apple-macos15.0"

echo "==> Building SplitLaneCore (needed for its .swiftmodule)"
swift build >/dev/null

MODULES=(-I .build/debug/Modules -I .build/debug)

echo "==> Type-checking SplitLaneProxyExtension (Swift 5 + strict concurrency, see ADR 0008)"
swiftc -typecheck -sdk "$SDK" -target "$TARGET" \
    -swift-version 5 -strict-concurrency=complete \
    "${MODULES[@]}" \
    $(find SplitLaneProxyExtension -name '*.swift')

echo "==> Type-checking SplitLane host app (Swift 6)"
swiftc -typecheck -sdk "$SDK" -target "$TARGET" \
    -swift-version 6 \
    "${MODULES[@]}" \
    $(find SplitLane -name '*.swift')

echo "==> Both targets type-check with no errors or warnings"
