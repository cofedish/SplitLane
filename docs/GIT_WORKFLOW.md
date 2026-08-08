# SplitLane Git Workflow

## Identity

Commits and pushes are made as `cofedish` only:

```bash
git config user.name  "cofedish"
git config user.email "57003706+cofedish@users.noreply.github.com"
```

Repo-local, not global. Verify with `git log --format='%an <%ae>' -3` before pushing.

## Mandatory pre-flight

Before **every** meaningful series of changes:

```bash
git status --short
git branch --show-current
git remote -v
```

If any remote exists:

```bash
git fetch --all --prune
git status -sb
```

If the branch has an upstream, quantify divergence before touching anything:

```bash
git rev-list --left-right --count HEAD...@{upstream}     # <ahead>	<behind>
```

Never begin a large modification without knowing the current state.

## Remote freshness

If a remote exists, treat local state as potentially stale until `git fetch` has run. Fetch before
changes and again before pushing.

## Safe fast-forward

Only when **all** of these hold — working tree clean, branch has an upstream, local is strictly
behind, no divergence:

```bash
git pull --ff-only
git status -sb        # re-check afterwards
```

## Never automatic

These are destructive and require an explicit instruction from the user, every time:

```
git reset --hard
git clean -fd
git push --force
git push --force-with-lease
blind git stash / git stash pop
any history rewrite (rebase -i, filter-branch, amend of pushed commits)
```

Unknown local changes are never discarded. If the working tree is dirty, determine where the
changes came from first. If local and remote have diverged, do not paper over it — preserve the
work and describe the state precisely, including both counts from `rev-list --left-right`.

## Branches

`main` is the primary branch. Feature branches for substantial work:

```
feature/bootstrap
feature/transparent-proxy
feature/app-routing
feature/socks5
feature/tcp-relay
feature/activity
```

One branch per coherent body of work, not one per file. Large experimental work does not go
directly on `main` once a feature workflow exists.

## Commits

Before committing:

```bash
git diff                 # read it
git status --short
git diff --cached
swift build && swift test
```

Check for secrets: no team IDs, certificates, provisioning profiles, `Local.xcconfig`, tokens, or
proxy passwords. `.gitignore` covers the known cases; the diff review covers the rest.

Conventional prefixes, imperative mood:

```
chore: bootstrap SplitLane project
docs:  add architecture, networking and threat model
feat:  add transparent proxy system extension
feat:  identify source applications from network flows
feat:  implement SOCKS5 client
fix:   close flow on SOCKS5 negotiation failure
test:  cover SOCKS5 reply truncation
```

One commit per completed logical milestone. Not one giant commit for the whole project, and not a
commit that leaves the build broken while claiming a milestone is done.

## Push

A remote existing is not permission for destructive remote operations. Before pushing:

```bash
git fetch --all --prune
git rev-list --left-right --count HEAD...@{upstream}
swift build && swift test
git push
```

Force push only on an explicit, specific instruction from the user.
