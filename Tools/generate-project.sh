#!/usr/bin/env bash
# Generate SplitLane.xcodeproj from project.yml.
#
# Use this rather than bare `xcodegen generate`: project.yml references Local.xcconfig, which is
# git-ignored, so a fresh clone has no such file and xcodegen fails validation with
# "Invalid config file". This seeds it from the committed example first.
set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v xcodegen >/dev/null 2>&1; then
    echo "!! xcodegen is not installed. Run: brew install xcodegen" >&2
    exit 1
fi

if [ ! -f Local.xcconfig ]; then
    echo "==> Local.xcconfig missing; seeding from Local.xcconfig.example"
    cp Local.xcconfig.example Local.xcconfig
    echo "    Edit Local.xcconfig and set DEVELOPMENT_TEAM before building."
    echo "    See docs/DEVELOPMENT.md -> Gate 2."
fi

xcodegen generate --spec project.yml

cat <<'NEXT'

Generated SplitLane.xcodeproj.

  xcodebuild -project SplitLane.xcodeproj -list
  xcodebuild -project SplitLane.xcodeproj -scheme SplitLane -configuration Debug build

Requires Xcode (not just Command Line Tools) and a Team ID in Local.xcconfig.
NEXT
