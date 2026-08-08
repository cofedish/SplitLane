---
name: git-project-workflow
description: SplitLane's Git workflow — mandatory pre-flight inspection, remote freshness, safe fast-forward, branching, commit discipline, push policy, divergence handling, and the list of prohibited destructive operations. Use before starting any meaningful series of changes, before committing, and before pushing.
---

# SplitLane Git workflow

## Identity — non-negotiable

Commits and pushes are made as `cofedish` only.

```bash
git config user.name  "cofedish"
git config user.email "57003706+cofedish@users.noreply.github.com"
git log --format='%an <%ae>' -3        # verify before pushing
```

Repo-local config. If a commit was authored with any other identity, fix it before it is pushed.

## Pre-flight — before every meaningful change series

```bash
git status --short
git branch --show-current
git remote -v
```

If any remote exists:

```bash
git fetch --all --prune
git status -sb
git rev-list --left-right --count HEAD...@{upstream}   # <ahead>	<behind>
```

Do not start a large modification without knowing the answer to: is the tree clean, does the
branch have an upstream, and how far apart are they?

## Remote freshness

With a remote present, local state is potentially stale until `git fetch` runs. Fetch before
changes and again before pushing.

## Safe fast-forward

Only when **all** hold: clean tree, upstream exists, strictly behind, no divergence.

```bash
git pull --ff-only
git status -sb
```

## Prohibited without an explicit user instruction

```
git reset --hard
git clean -fd
git push --force
git push --force-with-lease
blind git stash / git stash pop
history rewrite (rebase -i, filter-branch, amend of pushed commits)
```

Never discard unknown local changes. If the tree is dirty, find out where the changes came from
first. If local and remote diverged, do not hide it: preserve the work, report both counts from
`rev-list --left-right`, and stop before doing anything destructive.

## Branches

`main` is primary. Feature branches for substantial work:

```
feature/bootstrap  feature/transparent-proxy  feature/app-routing
feature/socks5     feature/tcp-relay          feature/activity
```

One branch per coherent body of work. Not one per file, and no large experimental work directly on
`main` once a feature workflow exists.

## Commit checklist

```bash
git diff                 # actually read it
git diff --cached
git status --short
swift build && swift test
```

Secrets check — none of these may appear in a diff: team IDs, `.p12`, `.cer`,
`.provisionprofile`, `Local.xcconfig`, tokens, proxy passwords, personal email addresses.

Message format, imperative mood:

```
chore: bootstrap SplitLane project
docs:  add architecture, networking and threat model
feat:  implement SOCKS5 client
fix:   close flow on SOCKS5 negotiation failure
test:  cover SOCKS5 reply truncation
```

One commit per completed logical milestone. Never commit a broken build as a finished milestone.

## Push

```bash
git fetch --all --prune
git rev-list --left-right --count HEAD...@{upstream}
swift build && swift test
git push
```

A remote existing is not permission for destructive remote operations. Force push only on a
specific, explicit instruction.

## Before stopping at an external gate

The project stops at real gates (Xcode install, Apple Developer enrolment, system extension
approval). Before stopping:

1. Commit all completed work — do not leave a milestone half-saved.
2. Leave the working tree understandable (`git status --short` should be empty or explainable).
3. Write down the one concrete manual action, and how to verify it succeeded.
4. State which milestone resumes afterwards.
