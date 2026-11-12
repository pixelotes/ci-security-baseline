# Runbook: false positives

A baseline that cries wolf ends up ignored. The goal is not zero findings, it
is that **every finding that blocks is worth the interruption**.

## Decision tree

```
Is the finding real in this context?
├─ Yes → fix it
└─ No
   ├─ Would it fail the same way in other repos?
   │  ├─ Yes → fix the RULE in ci-security-baseline (benefits everyone)
   │  └─ No  → local exception with scope, reason, owner and expires
   └─ Is it systematic tool noise?
      └─ adjust policy/severity-map.yml or the allowlist in policy/
```

The question that matters is the second one: if the same false positive is
going to show up in twenty repos, twenty local exceptions are twenty places
to maintain the same thing.

## Where each thing gets fixed

| Symptom | Place |
|---|---|
| Opengrep rule with too much noise | `policy/semgrep/` or the module's `config` |
| Gitleaks flags test files | `policy/gitleaks.toml` → `allowlist.paths` |
| Disproportionate severity from a tool | `policy/severity-map.yml` → `overrides` |
| Checkov with checks that do not apply to the org | `policy/checkov/` |
| Affects only one repository | that repo's `.security-baseline.yml` |

## Signs the threshold is wrong, not the teams

Each rollout wave has an exit criterion. Watch:

- **Rate of new exceptions per week.** If it grows wave after wave, the problem
  is the policy, not team discipline.
- **Median PR time.** If it rises steadily after enabling the gate, either the
  pipeline is slow (check the cache) or it blocks too much.
- **Exceptions renewed without a change of `reason`.** A sign the rule does not
  apply to that context and has to be fixed upstream.

## Escalation

1. Issue in `ci-security-baseline` with the `false-positive` label, attaching
   the job's SARIF.
2. If it blocks a delivery, local exception with a short `expires` (30 days)
   and the issue linked in `reason`.
3. `@pixelotes` decides whether the rule is adjusted, reclassified or kept.
