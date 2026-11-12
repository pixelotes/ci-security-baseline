# Adopting the security baseline

## What will happen in your repository

Two files are added:

- `.github/workflows/ci.yml` — calls the baseline. It must not grow.
- `.security-baseline.yml` — gate threshold, cutoff date and exceptions.

A new check called **`gate`** also appears on your pull requests. It is the only
required check the baseline adds.

## What the gate does

The scanners (opengrep, gitleaks, osv-scanner, trivy, checkov, hadolint) **never fail**.
They emit SARIF and move on. The `gate` aggregates them, normalizes severity
across tools, applies your exceptions and the cutoff date, and decides.

If it blocks, you will see a comment on the PR with the findings table, the
exact location and the rule. That comment is updated on every push; comments
do not pile up.

## What does NOT block

- **Lint** (checkstyle, ruff, eslint, tflint…) flags quality, not risk.
  It runs with `continue-on-error` and annotates, but does not prevent the
  merge. Mixing it into the gate would let a misconfigured `prettier` block a
  hotfix.
- Findings **below the threshold** of your repo (by default, anything that is
  not `high` or `critical`).
- Findings **older than the cutoff date**, for 90 days.

## The cutoff date

When you adopt the baseline in a repo with history, `cutoff` downgrades to a
warning everything introduced before that date. Anything you touch from then on
does block.

```yaml
gate:
  severity: high
  cutoff: '2026-10-01'
```

It is not an indefinite amnesty: those findings appear in the PR comment inside
a collapsible section and have to be drained. But it lets the gate take effect
without stopping the team on day one.

## Before the first commit

```bash
pip install pre-commit
pre-commit install
```

The Team plan does not include push protection on private repos. This hook is
the only barrier before a secret reaches the server.

## If the gate blocks you

1. **Fix it.** That is the right call in most cases.
2. **If it is a false positive or not exploitable**, declare an exception in
   `.security-baseline.yml`. See [exceptions.md](exceptions.md).
3. **If you think the rule is wrong**, open an issue in `ci-security-baseline`:
   fixing the rule there benefits every repo. See
   [runbook-false-positives.md](runbook-false-positives.md).

What is not acceptable is disabling the check.
