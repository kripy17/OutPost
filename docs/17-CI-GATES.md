# CI Gates & Branch Protection

How `main` stays green and why a stale badge — or any red check — cannot merge.

## The gate stack (in order)

Every push to `main` and every pull request runs the `CI` workflow
(`.github/workflows/ci.yml`) with two parallel jobs:

| Job | What it runs | Fails on |
|---|---|---|
| `verify.sh — backend · collectors · CLI · frontend` | Fast-fail ladder, then the full sweep | stale badges/README claims, tsc errors, failing pytest/vitest, collector FP-baseline soaks, layout overflow, post-deploy walk |
| `Deploy — web image + Caddyfile + compose` | Production image build + config validation | Dockerfile/Caddyfile/compose drift |

Inside the verify job, three fast-fail tiers front-load the expensive checks
so the cheapest signal fails first. The sweep itself is 16 steps; beyond the
suites it includes the **identity gate** (`scripts/gate_proc_identity.py`) —
an AST scan of the detection/process-tree/baseline/CLI-rendering modules that
fails if any event-level `process_name` read lacks an `exe_path` resolution,
locking the process-identity fallback so a future rule can't silently regress
to name-only matching that skips nameless rows.

1. **`npx tsc --noEmit`** (~1 min in) — frontend type errors fail before the
   Playwright download.
2. **`bash scripts/refresh-badges.sh --check`** (~1.5 min in) — a stale badge
   or README count fails before the 3.5-min sweep. Collect-only
   (`pytest --collect-only` + `vitest list`), so it costs seconds.
3. **`bash verify.sh`** — the full sweep (tests, soaks, layout sweep,
   post-deploy walk, badge refresh gate).

A dedicated `Refresh dynamic badges` job runs on the **weekly schedule and
`workflow_dispatch` only** — it recomputes the four badge payloads from
`main` and commits any change, so badges self-heal without a code push.

## Branch protection on `main`

`main` is protected with **required status checks**:

- **Required checks**: `verify.sh — backend · collectors · CLI · frontend`
  and `Deploy — web image + Caddyfile + compose`
- **Strict mode**: on (branches must be up to date with `main` before merge)
- **Admins**: not enforced (admins can still merge in emergencies)

The badge gate is *enforceable* because the fast-fail runs inside the
required `verify.sh` check: a PR that carries a stale
`badges/tests.json` (or a README count that no longer matches reality) goes
red on that check, and branch protection refuses the merge. The same rule
blocks broken frontend builds, failing tests, and soak-FP regressions.

### The trap to avoid

Never add `Refresh dynamic badges` to the required checks. That job only
runs on `schedule`/`workflow_dispatch`, so it never appears on a PR — a
required check that never runs makes every PR permanently unmergeable.

## Auto-merge policy: green PRs merge themselves

The repo has `allow_auto_merge` enabled, so a PR merges **automatically the
instant the two required checks pass** — no human click needed. Combined
with strict mode, only fully-green, up-to-date PRs ever merge.

Per PR, the author opts in with one command:

```bash
gh pr merge <number> --auto --squash
```

(or the **Enable auto-merge** button in the PR sidebar). The PR then waits
for the required checks to pass and merges itself; the "Auto-merge will
merge this pull request when all required checks pass" state is visible on
the PR. No required reviews are configured, so green = merge.

Why auto-merge instead of a merge queue: GitHub's merge queue is not
exposable through the REST/GraphQL API (it is a UI-only branch setting), so
it cannot be applied as a repo policy from a script. Auto-merge achieves the
same outcome — "merge when green, without waiting" — and is the right scale
for a solo-maintainer repo. (If fleet-scale concurrent merging is ever
needed, enable the queue in the branch-protection UI and keep this policy.)

Notes:
- The badge-refresh bot commits directly to `main` (no PR), so auto-merge
  never touches it.
- Admin bypass still applies: `enforce_admins` is false, so an admin can
  force-merge a red PR with `gh pr merge --admin` in an emergency.

To make this the default for every new PR, use the helper:

```bash
bash scripts/new-pr.sh "Title of the PR" "Optional body"
```

It pushes the current branch, opens the PR, and arms `--auto --squash` in
one step (refuses to run from a detached HEAD or `main`).

### If you ever need the merge queue (high-volume weeks)

GitHub's merge queue **cannot be enabled through the REST or GraphQL API**
— it is a UI-only branch setting (verified by schema introspection: the
protection-rule mutation exposes no queue field). If concurrent merges ever
need sequential re-testing against the latest `main`, enable it by hand
once:

1. Repo **Settings → Branches → edit** the `main` protection rule.
2. Tick **Require merge queue** (it becomes available once required status
   checks are set, as they are here).
3. The merge button becomes **Merge when ready** — PRs enter the queue,
   are re-tested against the latest `main`, and merge in order. Pair it
   with `gh pr merge --auto` so green PRs enter the queue without a click.

The queue adds serialization overhead (each PR is built/tested once more in
the queue), so for a solo maintainer, plain auto-merge remains the better
default — this is the policy to keep unless merge traffic grows.

## Inspecting / changing the rule

```bash
# Read the current protection rule
gh api repos/kripy17/OutPost/branches/main/protection

# Replace the required checks (verify + deploy, strict, admins not enforced)
gh api -X PUT repos/kripy17/OutPost/branches/main/protection --input - <<'JSON'
{
  "required_status_checks": {
    "strict": true,
    "contexts": [
      "verify.sh — backend · collectors · CLI · frontend",
      "Deploy — web image + Caddyfile + compose"
    ]
  },
  "enforce_admins": false,
  "required_pull_request_reviews": null,
  "restrictions": null,
  "allow_force_pushes": false,
  "allow_deletions": false,
  "required_linear_history": false
}
JSON
```

Check names must match GitHub's registered runs exactly (the em-dash and
`·` characters included). List them with:

```bash
gh api repos/kripy17/OutPost/commits/<sha>/check-runs -q '.check_runs[].name'
```
