# Third-party skills

The directories listed below are vendored, unmodified, from **addyosmani/agent-skills**. Every other
skill directory here belongs to SplitLane and is not covered by this file.

| | |
|---|---|
| Source | https://github.com/addyosmani/agent-skills |
| Commit | `bcab6a1b8503100e8618c3b4e32cc78de43de769` (2026-09-22T21:05:38-07:00, plugin version 0.6.10) |
| License | MIT, Copyright (c) 2025 Addy Osmani. Full text: [`_agent-skills-LICENSE`](_agent-skills-LICENSE) (required by MIT; it also covers `../references/`) |
| Installed | 2026-09-23, project scope only (nothing written to `~/.claude`) |

## Install method

Upstream supports two Claude Code routes: its plugin marketplace, and `npx skills add
addyosmani/agent-skills`, which copies `skills/<name>/` into `.claude/skills/`. We reproduced the
second route by hand. The files are pinned to one commit, can be reviewed in git, and installing
them made no machine-level changes. The plugin route (`claude plugin install --scope project`)
records the plugin in project settings but still clones and caches it under `~/.claude/plugins/`.
It also brings in commands and agents that we did not want.

In upstream's layout, the skills link to the shared checklists as `../../references/*.md`. The
checklists are therefore copied to `.claude/references/`, so every link works without changing any
file (upstream issue #361).

## Installed (25 skills + 7 shared references)

api-and-interface-design, browser-testing-with-devtools, ci-cd-and-automation,
code-review-and-quality, code-simplification, constraint-driven-development, context-engineering,
debugging-and-error-recovery, deprecation-and-migration, documentation-and-adrs,
doubt-driven-development, frontend-ui-engineering, git-workflow-and-versioning, idea-refine,
incremental-implementation, interview-me, observability-and-instrumentation,
performance-optimization, planning-and-task-breakdown, security-and-hardening, shipping-and-launch,
source-driven-development, spec-driven-development, test-driven-development, using-agent-skills.

`../references/`: accessibility-checklist, definition-of-done, observability-checklist,
orchestration-patterns, performance-checklist, security-checklist, testing-patterns (`.md`).

Note: `idea-refine/scripts/idea-refine.sh` is the only executable file included. It runs only when
invoked manually and does nothing but `mkdir -p docs/ideas`. Its SKILL.md gives the path relative to
upstream's repo root (`skills/idea-refine/...`), which does not exist here.

## Deliberately not installed

- `hooks/`: shell hooks (the SDD cache hooks call `curl`). Upstream's plugin does not wire them either.
- `.claude/commands/` (`/spec`, `/plan`, `/build`, ...): these invoke the `agent-skills:<name>` plugin
  namespace, which does not exist in a vendored install. Invoke the skills by name instead.
- `agents/` (4 subagent personas): not skills. Some skills mention them.
- `scripts/`, `evals/`, `.github/`, adapters for other tools (`.gemini/`, `.codex-plugin/`, `.agents/`,
  `.opencode/`, `commands/*.toml`, `plugin.json`), and upstream's `CLAUDE.md`/`AGENTS.md`/`.claude/rules/`.
  Upstream says not to copy the last three.

## Update

```bash
UP=<scratch-dir>/agent-skills            # outside this repo
git clone --depth 1 https://github.com/addyosmani/agent-skills.git "$UP"
git -C "$UP" log -1 --format='%H %cI'    # record the new SHA/date above
cd E:/Projects/SplitLane/.claude
for d in "$UP"/skills/*/; do case $(basename "$d") in
  build-and-test|git-project-workflow|network-extension-debug|splitlane-architecture)
    echo "COLLISION: $(basename "$d") - do not copy";; esac; done
diff -r "$UP/skills" skills; diff -r "$UP/references" references; diff "$UP/LICENSE" skills/_agent-skills-LICENSE
cp -r "$UP"/skills/<name> skills/        # per reviewed skill; delete files upstream removed
cp "$UP"/references/*.md references/ && cp "$UP/LICENSE" skills/_agent-skills-LICENSE
```

Update this file afterwards: record the new SHA, date and skill list.
