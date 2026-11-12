# Exceptions

## Format

```yaml
exceptions:
  - id: CVE-2025-48795          # ruleId or CVE
    tool: trivy                 # optional: restrict to one tool
    scope: 'pom.xml'            # optional: glob on the path
    reason: 'Not exploitable: the XML parser receives no external input'
    owner: '@pixelotes/team-alpha'
    expires: '2026-12-15'       # MANDATORY
```

## `expires` is mandatory

An exception without an expiry date makes the **gate fail**, even if there is
no blocking finding. This is not a design oversight: it is the design.

Without expiry, the exceptions file grows monotonically and in six months the
gate blocks nothing while the dashboard stays green. With expiry, every
exception comes back to the table with a named owner.

When one expires, the gate fails and the message says which one. Renewing it is
explicit and stays in git history: who, when and why.

## `reason` gets read

Write why **this** finding does not apply, not what the vulnerability is.

- Bad: `'CVE in the XML library'`
- Good: `'The parser only processes files from the repository itself; there is
  no external input that could contain a malicious entity'`

Whoever reviews the renewal three months from now does not have your context
from today.

## Good practices for `scope`

Narrow it whenever you can. An exception without `scope` applies to the whole
repo, so an identical vulnerability in a new module passes without anyone
seeing it.

```yaml
scope: 'src/test/resources/fixtures/**'   # good
scope: '**'                               # same as leaving it out
```

## What is NOT excepted

- **Secrets verified by TruffleHog.** They are confirmed against the provider.
  They get rotated, not excepted.
- **Public exposure of resources in IaC** (`CKV_*_public_*`). If it really has
  to be public, it goes through a documented architecture decision, not a line
  in a YAML file.

## Review

`CODEOWNERS` makes `@pixelotes` a mandatory reviewer of
`.security-baseline.yml`. An unreviewed exception is the quietest way to
disable the gate.
