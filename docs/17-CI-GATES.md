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
so the cheapest signal fails first:

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
